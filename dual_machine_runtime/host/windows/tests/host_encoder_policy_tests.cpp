#include "vfdual/host_encoder_policy.hpp"

#include <cstdlib>
#include <iostream>

namespace {

void require(bool condition, const char* expression, int line) {
    if (condition) return;
    std::cerr << "host_encoder_policy_tests.cpp:" << line
              << ": CHECK failed: " << expression << '\n';
    std::exit(EXIT_FAILURE);
}

#define CHECK(expression) require(static_cast<bool>(expression), #expression, __LINE__)

void verify_automatic_policy(
    vfdual::GraphicsAdapterVendor vendor,
    vfdual::HostEncoderCandidate expected_nvenc,
    std::size_t expected_size) {
    const auto candidates = vfdual::choose_host_encoder_candidates(
        vfdual::H264EncoderPreference::automatic, vendor);
    CHECK(candidates.size == expected_size);
    CHECK(candidates.values[0] == expected_nvenc);
    const std::size_t generic_fallback_index = expected_size - 2U;
    CHECK(candidates.values[generic_fallback_index] ==
          vfdual::HostEncoderCandidate::windows_hardware_capture_device);
    CHECK(candidates.values[generic_fallback_index + 1U] ==
          vfdual::HostEncoderCandidate::software_cpu);
}

}  // namespace

int main() {
    using namespace vfdual;
    CHECK(host_async_pipeline_supports_capture_extent(416U, 416U, 416U, 416U));
    CHECK(!host_async_pipeline_supports_capture_extent(415U, 413U, 416U, 416U));
    CHECK(!host_async_pipeline_supports_capture_extent(240U, 200U, 416U, 416U));
    CHECK(!host_async_pipeline_supports_capture_extent(0U, 0U, 416U, 416U));

    verify_automatic_policy(
        GraphicsAdapterVendor::nvidia,
        HostEncoderCandidate::nvenc_same_adapter_async_shared,
        4U);
    const auto nvidia_automatic = choose_host_encoder_candidates(
        H264EncoderPreference::automatic,
        GraphicsAdapterVendor::nvidia);
    CHECK(nvidia_automatic.values[1] ==
          HostEncoderCandidate::nvenc_capture_device);
    for (const auto vendor : {
             GraphicsAdapterVendor::intel,
             GraphicsAdapterVendor::amd,
             GraphicsAdapterVendor::microsoft,
             GraphicsAdapterVendor::unknown}) {
        verify_automatic_policy(
            vendor,
            HostEncoderCandidate::nvenc_cross_adapter,
            3U);
    }

    const auto media_foundation = choose_host_encoder_candidates(
        H264EncoderPreference::media_foundation,
        GraphicsAdapterVendor::intel);
    CHECK(media_foundation.size == 2U);
    CHECK(media_foundation.values[0] ==
          HostEncoderCandidate::windows_hardware_capture_device);
    CHECK(media_foundation.values[1] == HostEncoderCandidate::software_cpu);

    const auto software = choose_host_encoder_candidates(
        H264EncoderPreference::software, GraphicsAdapterVendor::amd);
    CHECK(software.size == 1U);
    CHECK(software.values[0] == HostEncoderCandidate::software_cpu);

    const auto native_nvenc = choose_host_encoder_candidates(
        H264EncoderPreference::nvenc, GraphicsAdapterVendor::nvidia);
    CHECK(native_nvenc.size == 1U);
    CHECK(native_nvenc.values[0] ==
          HostEncoderCandidate::nvenc_capture_device);

    const auto cross_adapter_nvenc = choose_host_encoder_candidates(
        H264EncoderPreference::nvenc, GraphicsAdapterVendor::intel);
    CHECK(cross_adapter_nvenc.size == 1U);
    CHECK(cross_adapter_nvenc.values[0] ==
          HostEncoderCandidate::nvenc_cross_adapter);

    const auto nvidia_without_async = choose_host_encoder_candidates(
        H264EncoderPreference::automatic_without_async_shared,
        GraphicsAdapterVendor::nvidia);
    CHECK(nvidia_without_async.size == 3U);
    CHECK(nvidia_without_async.values[0] ==
          HostEncoderCandidate::nvenc_capture_device);
    CHECK(nvidia_without_async.values[1] ==
          HostEncoderCandidate::windows_hardware_capture_device);
    CHECK(nvidia_without_async.values[2] ==
          HostEncoderCandidate::software_cpu);
    return 0;
}
