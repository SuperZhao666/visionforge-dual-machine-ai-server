#include "vfdual/media_foundation_h264_encoder.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <d3d11.h>
#include <dxgi1_2.h>
#include <wrl/client.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
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

namespace {

bool contains_nal(std::span<const std::byte> data, std::uint8_t expected) {
    for (std::size_t index = 0; index + 4U < data.size(); ++index) {
        const bool short_start = data[index] == std::byte{0} && data[index + 1U] == std::byte{0} &&
                                 data[index + 2U] == std::byte{1};
        const bool long_start = index + 5U < data.size() && data[index] == std::byte{0} &&
                                data[index + 1U] == std::byte{0} && data[index + 2U] == std::byte{0} &&
                                data[index + 3U] == std::byte{1};
        if (!short_start && !long_start) continue;
        const auto type = std::to_integer<std::uint8_t>(data[index + (long_start ? 4U : 3U)]) & 0x1fU;
        if (type == expected) return true;
    }
    return false;
}

std::uint64_t percentile50(std::vector<std::uint64_t> values) {
    std::sort(values.begin(), values.end());
    return values[values.size() / 2U];
}

void verify_encoder_policy() {
    using namespace vfdual;
    const auto nvidia = choose_host_encoder_candidates(
        H264EncoderPreference::automatic, GraphicsAdapterVendor::nvidia);
    CHECK(nvidia.size == 4U);
    CHECK(nvidia.values[0] == HostEncoderCandidate::nvenc_same_adapter_async_shared);
    CHECK(nvidia.values[1] == HostEncoderCandidate::nvenc_capture_device);
    CHECK(nvidia.values[2] == HostEncoderCandidate::windows_hardware_capture_device);
    CHECK(nvidia.values[3] == HostEncoderCandidate::software_cpu);

    for (const auto vendor : {GraphicsAdapterVendor::intel, GraphicsAdapterVendor::amd}) {
        const auto hybrid = choose_host_encoder_candidates(H264EncoderPreference::automatic, vendor);
        CHECK(hybrid.size == 3U);
        CHECK(hybrid.values[0] == HostEncoderCandidate::nvenc_cross_adapter);
        CHECK(hybrid.values[1] == HostEncoderCandidate::windows_hardware_capture_device);
        CHECK(hybrid.values[2] == HostEncoderCandidate::software_cpu);
    }
    const auto media_foundation = choose_host_encoder_candidates(
        H264EncoderPreference::media_foundation, GraphicsAdapterVendor::intel);
    CHECK(media_foundation.size == 2U);
    CHECK(media_foundation.values[0] == HostEncoderCandidate::windows_hardware_capture_device);
    CHECK(media_foundation.values[1] == HostEncoderCandidate::software_cpu);
    const auto software = choose_host_encoder_candidates(
        H264EncoderPreference::software, GraphicsAdapterVendor::intel);
    CHECK(software.size == 1U && software.values[0] == HostEncoderCandidate::software_cpu);
}

void benchmark_adapter_hardware_encoders(
    const vfdual::H264EncoderConfig& config, const std::vector<std::uint8_t>& pixels) {
    Microsoft::WRL::ComPtr<IDXGIFactory1> factory;
    if (FAILED(CreateDXGIFactory1(IID_PPV_ARGS(&factory)))) return;
    for (UINT index = 0;; ++index) {
        Microsoft::WRL::ComPtr<IDXGIAdapter1> adapter;
        if (factory->EnumAdapters1(index, &adapter) == DXGI_ERROR_NOT_FOUND) break;
        DXGI_ADAPTER_DESC1 adapter_description{};
        adapter->GetDesc1(&adapter_description);
        Microsoft::WRL::ComPtr<ID3D11Device> device;
        Microsoft::WRL::ComPtr<ID3D11DeviceContext> context;
        D3D_FEATURE_LEVEL selected{};
        const D3D_FEATURE_LEVEL levels[]{D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0};
        const HRESULT device_result = D3D11CreateDevice(
            adapter.Get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            levels, static_cast<UINT>(std::size(levels)), D3D11_SDK_VERSION,
            &device, &selected, &context);
        if (FAILED(device_result)) continue;
        std::cerr << "probing_adapter=" << index << '\n';
        const auto probe = vfdual::probe_media_foundation_h264_hardware(device.Get());
        std::cerr << "probed_adapter=" << index << '\n';
        std::cerr << "probe_values adapter=" << index
                   << " vendor_id=" << probe.adapter_vendor_id
                   << " luid_high=" << probe.adapter_luid_high
                   << " luid_low=" << probe.adapter_luid_low
                   << " count=" << probe.matching_hardware_transforms
                   << " activation=" << probe.activation_succeeded
                   << " transform_name=\"" << probe.transform_name << "\""
                   << " transform_clsid=" << probe.transform_clsid
                   << " hresult=" << probe.hresult << '\n';
        if (!probe.activation_succeeded) continue;

        D3D11_TEXTURE2D_DESC texture_description{};
        texture_description.Width = config.width;
        texture_description.Height = config.height;
        texture_description.MipLevels = 1;
        texture_description.ArraySize = 1;
        texture_description.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
        texture_description.SampleDesc.Count = 1;
        texture_description.Usage = D3D11_USAGE_DEFAULT;
        Microsoft::WRL::ComPtr<ID3D11Texture2D> texture;
        if (FAILED(device->CreateTexture2D(&texture_description, nullptr, &texture))) continue;
        context->UpdateSubresource(texture.Get(), 0, nullptr, pixels.data(), config.width * 4U, 0);
        for (const std::uint32_t timing_fps : {config.frames_per_second, 144U, 120U, 60U}) {
            vfdual::H264EncoderConfig candidate = config;
            candidate.frames_per_second = timing_fps;
            vfdual::MediaFoundationH264Encoder hardware_encoder;
            const bool initialized = hardware_encoder.initialize(
                device.Get(), candidate, vfdual::MediaFoundationEncoderMode::hardware);
            std::cerr << "adapter=" << index << " timing_fps=" << timing_fps
                      << " hardware_initialized=" << initialized
                      << " initialize_hresult=" << hardware_encoder.last_hresult() << '\n';
            if (!initialized) continue;
            CHECK(hardware_encoder.is_hardware());
            CHECK(hardware_encoder.adapter_vendor_id() == probe.adapter_vendor_id);
            CHECK(hardware_encoder.adapter_luid_low() == probe.adapter_luid_low);
            CHECK(hardware_encoder.adapter_luid_high() == probe.adapter_luid_high);
            CHECK(hardware_encoder.matching_hardware_transforms() > 0U);
            CHECK(!hardware_encoder.transform_name().empty());
            std::vector<std::uint64_t> timings;
            for (std::uint32_t frame = 0; frame < 120U; ++frame) {
                const auto started = std::chrono::steady_clock::now();
                const auto encoded = hardware_encoder.encode(texture.Get(), frame == 0U);
                const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - started).count();
                if (!encoded.success) {
                    std::cerr << "hardware_encode_failed adapter=" << index
                              << " timing_fps=" << timing_fps
                              << " frame=" << frame << " hresult=" << encoded.hresult
                              << " stage=" << static_cast<int>(encoded.stage) << '\n';
                    break;
                }
                if (frame >= 20U) timings.push_back(static_cast<std::uint64_t>(elapsed));
            }
            if (!timings.empty()) {
                const auto p50_us = percentile50(timings);
                std::cout << "adapter=" << index << " timing_fps=" << timing_fps
                          << " hardware_frames=" << timings.size()
                          << " hardware_encode_p50_us=" << p50_us
                          << " theoretical_encode_fps=" << (1'000'000.0 / p50_us) << '\n';
            }
        }
    }
}

}  // namespace

int main() {
    verify_encoder_policy();
    std::cerr << "policy_ok\n";
    const auto null_probe =
        vfdual::probe_media_foundation_h264_hardware(nullptr);
    CHECK(!null_probe.activation_succeeded);
    CHECK(null_probe.matching_hardware_transforms == 0U);
    CHECK(null_probe.adapter_vendor == vfdual::GraphicsAdapterVendor::unknown);
    CHECK(null_probe.hresult == E_POINTER);
    constexpr std::uint32_t width = 320;
    constexpr std::uint32_t height = 320;
    Microsoft::WRL::ComPtr<ID3D11Device> device;
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> context;
    D3D_FEATURE_LEVEL selected{};
    const D3D_FEATURE_LEVEL levels[]{D3D_FEATURE_LEVEL_11_0};
    HRESULT result = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_WARP, nullptr,
                                       D3D11_CREATE_DEVICE_BGRA_SUPPORT, levels, 1,
                                       D3D11_SDK_VERSION, &device, &selected, &context);
    if (FAILED(result)) {
        std::cerr << "warp_device_failed hresult=" << result << '\n';
        return 1;
    }
    const auto warp_probe =
        vfdual::probe_media_foundation_h264_hardware(device.Get());
    CHECK(warp_probe.adapter_vendor == vfdual::GraphicsAdapterVendor::microsoft);
    CHECK(warp_probe.adapter_vendor_id == 0x1414U);
    CHECK(!warp_probe.activation_succeeded);
    CHECK(warp_probe.matching_hardware_transforms == 0U);
    D3D11_TEXTURE2D_DESC description{};
    description.Width = width;
    description.Height = height;
    description.MipLevels = 1;
    description.ArraySize = 1;
    description.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    description.SampleDesc.Count = 1;
    description.Usage = D3D11_USAGE_DEFAULT;
    Microsoft::WRL::ComPtr<ID3D11Texture2D> texture;
    result = device->CreateTexture2D(&description, nullptr, &texture);
    if (FAILED(result)) return 2;
    std::vector<std::uint8_t> pixels(static_cast<std::size_t>(width) * height * 4U);
    for (std::uint32_t y = 0; y < height; ++y) {
        for (std::uint32_t x = 0; x < width; ++x) {
            const std::size_t offset = (static_cast<std::size_t>(y) * width + x) * 4U;
            pixels[offset] = static_cast<std::uint8_t>(x % 256U);
            pixels[offset + 1U] = static_cast<std::uint8_t>(y % 256U);
            pixels[offset + 2U] = static_cast<std::uint8_t>((x + y) % 256U);
            pixels[offset + 3U] = 255U;
        }
    }
    context->UpdateSubresource(texture.Get(), 0, nullptr, pixels.data(), width * 4U, 0);

    vfdual::MediaFoundationH264Encoder encoder;
    if (!encoder.initialize(device.Get(), vfdual::H264EncoderConfig{width, height, 120, 120})) {
        std::cerr << "mf_initialize_failed hresult=" << encoder.last_hresult() << '\n';
        return 3;
    }
    CHECK(!encoder.is_hardware());
    CHECK(encoder.adapter_vendor() == vfdual::GraphicsAdapterVendor::microsoft);
    CHECK(encoder.adapter_vendor_id() == 0x1414U);
    CHECK(!encoder.transform_name().empty());
    CHECK(!encoder.transform_clsid().empty());
    std::cerr << "software_initialized\n";
    bool saw_idr{};
    bool saw_sps{};
    bool saw_pps{};
    std::vector<std::uint64_t> software_timings;
    for (std::uint32_t frame = 0; frame < 120U; ++frame) {
        const auto started = std::chrono::steady_clock::now();
        const auto encoded = encoder.encode(texture.Get(), frame == 0U);
        const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - started).count();
        if (!encoded.success) return 4;
        if (frame >= 20U) software_timings.push_back(static_cast<std::uint64_t>(elapsed));
        const auto access_unit = encoder.access_unit();
        saw_idr = saw_idr || contains_nal(access_unit, 5U);
        saw_sps = saw_sps || contains_nal(access_unit, 7U);
        saw_pps = saw_pps || contains_nal(access_unit, 8U);
    }
    if (!saw_idr || !saw_sps || !saw_pps) {
        std::cerr << "annex_b_contract_failed idr=" << saw_idr << " sps=" << saw_sps
                  << " pps=" << saw_pps << '\n';
        return 5;
    }
    const auto software_p50_us = percentile50(software_timings);
    std::cerr << "software_encoded\n";
    std::cout << "software_frames=" << software_timings.size()
              << " software_encode_p50_us=" << software_p50_us
              << " theoretical_encode_fps=" << (1'000'000.0 / software_p50_us) << '\n';
    char* hardware_benchmark{};
    std::size_t hardware_benchmark_size{};
    const auto environment_status = _dupenv_s(
        &hardware_benchmark, &hardware_benchmark_size,
        "VFDUAL_ENABLE_UNSAFE_HARDWARE_MFT_BENCHMARK");
    if (environment_status != 0) {
        std::cerr << "hardware_benchmark_environment_read_failed status="
                  << environment_status << '\n';
        return 6;
    }
    const bool hardware_benchmark_enabled =
        hardware_benchmark != nullptr && std::string_view{hardware_benchmark} == "1";
    std::free(hardware_benchmark);
    if (hardware_benchmark_enabled) {
        benchmark_adapter_hardware_encoders(
            vfdual::H264EncoderConfig{width, height, 240, 240}, pixels);
        std::cerr << "hardware_benchmark_complete\n";
    } else {
        std::cerr << "hardware_benchmark_skipped opt_in_required=1\n";
    }
    return 0;
}
